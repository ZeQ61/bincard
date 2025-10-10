package akin.city_card.buscard.service.abstracts;

import akin.city_card.buscard.core.request.RegisterCardRequest;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;

public interface BusCardService {
    ResponseEntity<?> registerCard(RegisterCardRequest req);

    ResponseEntity<?> readCard(String uid);

    ResponseEntity<?> topUpBalance(String uid, BigDecimal bigDecimal);

    ResponseEntity<?> getOn(String uid);
}
