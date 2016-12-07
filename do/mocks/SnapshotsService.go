package mocks

import do "github.com/digitalocean/doctl/do"
import mock "github.com/stretchr/testify/mock"

// SnapshotsService is an autogenerated mock type for the SnapshotsService type
type SnapshotsService struct {
	mock.Mock
}

// Delete provides a mock function with given fields: _a0
func (_m *SnapshotsService) Delete(_a0 string) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: _a0
func (_m *SnapshotsService) Get(_a0 string) (*do.Snapshot, error) {
	ret := _m.Called(_a0)

	var r0 *do.Snapshot
	if rf, ok := ret.Get(0).(func(string) *do.Snapshot); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*do.Snapshot)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields:
func (_m *SnapshotsService) List() (do.Snapshots, error) {
	ret := _m.Called()

	var r0 do.Snapshots
	if rf, ok := ret.Get(0).(func() do.Snapshots); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(do.Snapshots)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListDroplet provides a mock function with given fields:
func (_m *SnapshotsService) ListDroplet() (do.Snapshots, error) {
	ret := _m.Called()

	var r0 do.Snapshots
	if rf, ok := ret.Get(0).(func() do.Snapshots); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(do.Snapshots)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListVolume provides a mock function with given fields:
func (_m *SnapshotsService) ListVolume() (do.Snapshots, error) {
	ret := _m.Called()

	var r0 do.Snapshots
	if rf, ok := ret.Get(0).(func() do.Snapshots); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(do.Snapshots)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

var _ do.SnapshotsService = (*SnapshotsService)(nil)
