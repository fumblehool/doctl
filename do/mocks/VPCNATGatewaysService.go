// Code generated by MockGen. DO NOT EDIT.
// Source: vpc_nat_gateways.go
//
// Generated by this command:
//
//	mockgen -source vpc_nat_gateways.go -package=mocks VPCNATGatewaysService
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	godo "github.com/digitalocean/godo"
	gomock "go.uber.org/mock/gomock"
)

// MockVPCNATGatewaysService is a mock of VPCNATGatewaysService interface.
type MockVPCNATGatewaysService struct {
	ctrl     *gomock.Controller
	recorder *MockVPCNATGatewaysServiceMockRecorder
	isgomock struct{}
}

// MockVPCNATGatewaysServiceMockRecorder is the mock recorder for MockVPCNATGatewaysService.
type MockVPCNATGatewaysServiceMockRecorder struct {
	mock *MockVPCNATGatewaysService
}

// NewMockVPCNATGatewaysService creates a new mock instance.
func NewMockVPCNATGatewaysService(ctrl *gomock.Controller) *MockVPCNATGatewaysService {
	mock := &MockVPCNATGatewaysService{ctrl: ctrl}
	mock.recorder = &MockVPCNATGatewaysServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVPCNATGatewaysService) EXPECT() *MockVPCNATGatewaysServiceMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockVPCNATGatewaysService) Create(arg0 *godo.VPCNATGatewayRequest) (*godo.VPCNATGateway, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0)
	ret0, _ := ret[0].(*godo.VPCNATGateway)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockVPCNATGatewaysServiceMockRecorder) Create(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockVPCNATGatewaysService)(nil).Create), arg0)
}

// Delete mocks base method.
func (m *MockVPCNATGatewaysService) Delete(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockVPCNATGatewaysServiceMockRecorder) Delete(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockVPCNATGatewaysService)(nil).Delete), arg0)
}

// Get mocks base method.
func (m *MockVPCNATGatewaysService) Get(arg0 string) (*godo.VPCNATGateway, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0)
	ret0, _ := ret[0].(*godo.VPCNATGateway)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockVPCNATGatewaysServiceMockRecorder) Get(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockVPCNATGatewaysService)(nil).Get), arg0)
}

// List mocks base method.
func (m *MockVPCNATGatewaysService) List() ([]*godo.VPCNATGateway, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List")
	ret0, _ := ret[0].([]*godo.VPCNATGateway)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockVPCNATGatewaysServiceMockRecorder) List() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockVPCNATGatewaysService)(nil).List))
}

// Update mocks base method.
func (m *MockVPCNATGatewaysService) Update(arg0 string, arg1 *godo.VPCNATGatewayRequest) (*godo.VPCNATGateway, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", arg0, arg1)
	ret0, _ := ret[0].(*godo.VPCNATGateway)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Update indicates an expected call of Update.
func (mr *MockVPCNATGatewaysServiceMockRecorder) Update(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockVPCNATGatewaysService)(nil).Update), arg0, arg1)
}
