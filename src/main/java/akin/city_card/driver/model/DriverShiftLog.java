package akin.city_card.driver.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DriverShiftLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Driver driver;

    private LocalDateTime shiftStart;

    private LocalDateTime shiftEnd;

    private String note;

    private boolean approved;
}
