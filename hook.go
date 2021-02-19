package logrus_cloudwatchlogs

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/sirupsen/logrus"
)

type Hook struct {
	svc               *cloudwatchlogs.CloudWatchLogs
	groupName         string
	streamName        string
	nextSequenceToken *string
	m                 sync.Mutex
	ch                chan *cloudwatchlogs.InputLogEvent
	err               *error
	fields            logrus.Fields
	formatter         logrus.Formatter
}

// NewHook returns a new CloudWatch hook.
//
// CloudWatch log events are sent in batches on an interval, batchFrequency. Pass 0 to send events synchronously.
func NewHook(groupName, streamName string, sess *session.Session, batchFrequency time.Duration) (*Hook, error) {
	h := &Hook{
		svc:        cloudwatchlogs.New(sess),
		groupName:  groupName,
		streamName: streamName,
	}

	resp, err := h.getOrCreateCloudWatchLogGroup()
	if err != nil {
		return nil, err
	}

	if batchFrequency > 0 {
		h.ch = make(chan *cloudwatchlogs.InputLogEvent, 10000)
		go h.putBatches(time.NewTicker(batchFrequency).C)
	}

	// grab the next sequence token
	if len(resp.LogStreams) > 0 {
		h.nextSequenceToken = resp.LogStreams[0].UploadSequenceToken
		return h, nil
	}

	// create stream if it doesn't exist. the next sequence token will be null
	_, err = h.svc.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(groupName),
		LogStreamName: aws.String(streamName),
	})
	if err != nil {
		return nil, err
	}

	return h, nil
}

// WithFields includes the given fields to log entries sent to CloudWatch.
func (h *Hook) WithFields(fields logrus.Fields) *Hook {
	h.fields = fields
	return h
}

// WithFormatter uses the given formatter to format log entries sent to CloudWatch.
func (h *Hook) WithFormatter(formatter logrus.Formatter) *Hook {
	h.formatter = formatter
	return h
}

// Fire sends the given entry to CloudWatch.
func (h *Hook) Fire(entry *logrus.Entry) error {
	if h.fields != nil {
		// WithFields() resets the entry. Ensure that we pass data that gets reset.
		oldEntry := entry
		entry = entry.WithFields(h.fields)
		entry.Buffer = oldEntry.Buffer
		entry.Caller = oldEntry.Caller
		entry.Level = oldEntry.Level
		entry.Message = oldEntry.Message
	}

	var line string
	var err error
	if h.formatter != nil {
		var b []byte
		b, err = h.formatter.Format(entry)
		line = string(b)
	} else {
		line, err = entry.String()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read entry, %v", err)
		return err
	}

	switch entry.Level {
	case logrus.PanicLevel:
		fallthrough
	case logrus.FatalLevel:
		fallthrough
	case logrus.ErrorLevel:
		fallthrough
	case logrus.WarnLevel:
		fallthrough
	case logrus.InfoLevel:
		fallthrough
	case logrus.DebugLevel:
		_, err := h.Write([]byte(line))
		return err
	default:
		return nil
	}
}

// Write sends the given bytes to CloudWatch.
func (h *Hook) Write(p []byte) (n int, err error) {
	event := &cloudwatchlogs.InputLogEvent{
		Message:   aws.String(string(p)),
		Timestamp: aws.Int64(int64(time.Nanosecond) * time.Now().UnixNano() / int64(time.Millisecond)),
	}

	// Batching hook - send event via channel
	if h.ch != nil {
		h.ch <- event
		if h.err != nil {
			lastErr := h.err
			h.err = nil
			return 0, fmt.Errorf("%v", *lastErr)
		}
		return len(p), nil
	}

	// Synchronous hook - send event immediately
	h.sendBatch([]*cloudwatchlogs.InputLogEvent{event})
	return len(p), nil
}

func (h *Hook) getOrCreateCloudWatchLogGroup() (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
	resp, err := h.svc.DescribeLogStreams(&cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName:        aws.String(h.groupName),
		LogStreamNamePrefix: aws.String(h.streamName),
	})

	if err == nil {
		return resp, nil
	}

	aerr, ok := err.(awserr.Error)
	if ok && aerr.Code() == cloudwatchlogs.ErrCodeResourceNotFoundException {
		_, err = h.svc.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
			LogGroupName: aws.String(h.groupName),
		})
		if err != nil {
			return nil, err
		}
		return h.getOrCreateCloudWatchLogGroup()
	}

	return nil, err
}

func (h *Hook) putBatches(ticker <-chan time.Time) {
	var batch []*cloudwatchlogs.InputLogEvent
	size := 0
	for {
		select {
		case p := <-h.ch:
			messageSize := len(*p.Message) + 26
			if size+messageSize >= 1048576 || len(batch) == 10000 {
				go h.sendBatch(batch)
				batch = nil
				size = 0
			}
			batch = append(batch, p)
			size += messageSize
		case <-ticker:
			go h.sendBatch(batch)
			batch = nil
			size = 0
		}
	}
}

func (h *Hook) sendBatch(batch []*cloudwatchlogs.InputLogEvent) {
	h.m.Lock()
	defer h.m.Unlock()

	if len(batch) == 0 {
		return
	}

	params := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     batch,
		LogGroupName:  aws.String(h.groupName),
		LogStreamName: aws.String(h.streamName),
		SequenceToken: h.nextSequenceToken,
	}

	resp, err := h.svc.PutLogEvents(params)
	if err == nil {
		h.nextSequenceToken = resp.NextSequenceToken
		return
	}

	h.err = &err
	if aerr, ok := err.(*cloudwatchlogs.InvalidSequenceTokenException); ok {
		h.nextSequenceToken = aerr.ExpectedSequenceToken
		h.sendBatch(batch)
	}
}

func (h *Hook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}
