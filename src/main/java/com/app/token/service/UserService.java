package com.app.token.service;

import com.app.token.controller.request.UserCreateRequest;
import com.app.token.entity.Account;
import com.app.token.entity.Admin;
import com.app.token.entity.User;
import com.app.token.repository.AccountRepository;
import com.app.token.repository.AdminRepository;
import com.app.token.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AccountRepository accountRepository;
    private final UserRepository userRepository;
    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;

    public void register(UserCreateRequest request) {
        String email = request.email();
        checkDuplicateEmail(email);

        String encodedPassword = passwordEncoder.encode(request.password());
        Account newAccount = Account.create(email, encodedPassword);

        if (request.isAdmin()) {
            registerAdmin(newAccount);
        } else {
            registerUser(request, newAccount);
        }
    }

    private void registerUser(UserCreateRequest request, Account newAccount) {
        User newUser = User.create(newAccount, request.nickname());
        accountRepository.save(newAccount);
        userRepository.save(newUser);
    }

    private void registerAdmin(Account newAccount) {
        Admin newAdmin = Admin.create(newAccount);
        accountRepository.save(newAccount);
        adminRepository.save(newAdmin);
    }

    private void checkDuplicateEmail(String email) {
        accountRepository.findByEmail(email)
                .ifPresent(account -> {
                    throw new IllegalArgumentException("이미 사용중인 이메일입니다.");
                });
    }
}
