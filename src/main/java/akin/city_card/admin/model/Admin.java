package akin.city_card.admin.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@SuperBuilder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "admins")
public class Admin extends SecurityUser {

    @Column(name = "super_admin_approved", nullable = false)
    private boolean superAdminApproved;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "registered_at", nullable = false, updatable = false)
    private LocalDateTime registeredAt;


    @PrePersist
    protected void onCreate() {
        this.registeredAt = LocalDateTime.now();
    }
}
