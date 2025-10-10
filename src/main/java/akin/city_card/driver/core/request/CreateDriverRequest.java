package akin.city_card.driver.core.request;

import akin.city_card.driver.model.Shift;
import lombok.*;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateDriverRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String nationalId;
    private LocalDate dateOfBirth;
    private String licenseClass;
    private String licenseNumber;
    private LocalDate licenseExpiryDate;
    private LocalDate licenseIssueDate;
    private String address;
    private Shift shift;
}
