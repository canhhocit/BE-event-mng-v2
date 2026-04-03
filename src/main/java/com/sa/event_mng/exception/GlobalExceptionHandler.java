package com.sa.event_mng.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.sa.event_mng.dto.response.ApiResponse;

import lombok.extern.slf4j.Slf4j;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(value = Exception.class)
    @SuppressWarnings("rawtypes")
    ResponseEntity<ApiResponse> handlingException(Exception ex) {
        ApiResponse apiResponse = new ApiResponse();
        apiResponse.setCode(ErrorCode.UNCATEGORIZED_EXCEPTION.getCode());
        apiResponse.setMessage(ErrorCode.UNCATEGORIZED_EXCEPTION.getMessage());
        return ResponseEntity.badRequest().body(apiResponse);
    }

    @ExceptionHandler(value = AppException.class)
    @SuppressWarnings("rawtypes")
    ResponseEntity<ApiResponse> handlingAppException(AppException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        ApiResponse apiResponse = new ApiResponse();

        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage());

        return ResponseEntity.status(errorCode.getStatusCode()).body(apiResponse);
    }

    @ExceptionHandler(value = DisabledException.class)
    @SuppressWarnings("rawtypes")
    ResponseEntity<ApiResponse> handlingDisabledException(DisabledException ex) {
        ErrorCode errorCode = ErrorCode.USER_DISABLED;
        ApiResponse apiResponse = new ApiResponse();
        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(ex.getMessage());
        return ResponseEntity.status(errorCode.getStatusCode()).body(apiResponse);
    }

    @ExceptionHandler(value = AccessDeniedException.class)
    @SuppressWarnings("rawtypes")
    ResponseEntity<ApiResponse> handlingAccessDeniedException(AccessDeniedException ex) {
        ErrorCode errorCode = ErrorCode.UNAUTHORIZED;
        return ResponseEntity.status(errorCode.getStatusCode())
                .body(ApiResponse.builder()
                        .code(errorCode.getCode())
                        .message(errorCode.getMessage())
                        .build());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidationException(MethodArgumentNotValidException ex) {
        var fieldError = ex.getBindingResult().getFieldError();
        if (fieldError == null) {
            return ResponseEntity.badRequest().build();
        }
        String errorKey = fieldError.getDefaultMessage();

        ErrorCode errorCode = ErrorCode.KEY_INVALID;
        try {
            errorCode = ErrorCode.valueOf(errorKey);
        } catch (IllegalArgumentException e) {
            log.error("Unknown validation error key: {}", errorKey);
        }

        return ResponseEntity
                .status(errorCode.getStatusCode())
                .body(ApiResponse.builder()
                        .code(errorCode.getCode())
                        .message(errorCode.getMessage())
                        .build());
    }

    @ExceptionHandler(MailException.class)
    public ResponseEntity<ApiResponse<Object>> handleMailException(MailException ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.builder()
                        .code(9000)
                        .message("Email sending failed: "
                                + (ex.getRootCause() != null ? ex.getRootCause().getMessage() : ex.getMessage()))
                        .build());
    }
}
