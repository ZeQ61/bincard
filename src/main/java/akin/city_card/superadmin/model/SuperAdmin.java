package akin.city_card.superadmin.model;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SuperAdmin extends SecurityUser {



    @OneToMany(mappedBy = "approvedBy", cascade = CascadeType.ALL)
    private List<AdminApprovalRequest> approvedRequests;

    // Toplam kaç admin onayladığı (statistiksel amaçla)
    @Column(name = "total_approved_admins")
    private int totalApprovedAdmins;

}
