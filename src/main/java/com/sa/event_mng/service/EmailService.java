package com.sa.event_mng.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendVerificationEmail(String to, String token) {
        String subject = "[Event Manager] Xác thực Email - Email Verification";
        String verificationUrl = "http://localhost:8080/event-mng/auth/verify?token=" + token;
        String message = "Vui lòng nhấn vào liên kết bên dưới để xác thực email của bạn:\n" + verificationUrl + "\n\n" +
                         "--------------------------------------------------\n" +
                         "Please click the link below to verify your email:\n" + verificationUrl;

        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject(subject);
        email.setText(message);

        mailSender.send(email);
    }

    public void sendOtpEmail(String to, String otp) {
        String subject = "[Event Manager] Mã xác thực OTP - OTP Verification Code";
        String message = "Mã OTP để đặt lại mật khẩu của bạn là: " + otp + "\n" +
                         "Nếu bạn không yêu cầu, vui lòng bỏ qua email này.\n\n" +
                         "--------------------------------------------------\n" +
                         "Your OTP code for password reset is: " + otp + "\n" +
                         "If you did not request this, please ignore this email.";

        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject(subject);
        email.setText(message);

        mailSender.send(email);
    }

    public void sendOrderConfirmation(String to, String orderId, java.math.BigDecimal total) {
        String subject = "[Event Manager] Xác nhận thanh toán - Payment Confirmation #" + orderId;
        String message = "Chào bạn,\n\n" +
                "Chúng tôi gửi thư này để xác nhận bạn đã thanh toán thành công đơn hàng " + orderId + "\n" +
                "Cảm ơn bạn đã quan tâm và tin tưởng khi đặt vé qua nền tảng Event Manager của chúng tôi.\n" +
                "Tổng số tiền: " + String.format("%,.0f", total.doubleValue()) + "đ\n\n" +
                "Vui lòng truy cập vào ứng dụng để xem chi tiết vé. Chúc bạn có một buổi đi chơi thật vui vẻ và ý nghĩa!\n\n" +
                "Trân trọng!\n\n" +
                "--------------------------------------------------\n" +
                "Dear customer,\n\n" +
                "We are sending this email to confirm that your payment for order " + orderId + " was successful.\n" +
                "Thank you for choosing Event Manager.\n" +
                "Total amount: " + String.format("%,.0f", total.doubleValue()) + " VND\n\n" +
                "Please access the application to view your tickets. We hope you have a great time!\n\n" +
                "Best regards!";

        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject(subject);
        email.setText(message);

        mailSender.send(email);
    }
}
