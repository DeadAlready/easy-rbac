'use strict';

module.exports.catchError = catchError;
module.exports.shouldBeAllowed = shouldBeAllowed;
module.exports.shouldNotBeAllowed = shouldNotBeAllowed;

/**********************/

function shouldBeAllowed(done) {
  return function (result) {
    if(result) {
      done();
    } else {
      done(new Error('should not be denied'));
    }
  }
}

function shouldNotBeAllowed(done) {
  return function (result) {
    if(result) {
      done(new Error('should not be allowed'));
    } else {
      done();
    }
  }
}

function catchError(done) {
  return function (err) {
    return false;
  }
}