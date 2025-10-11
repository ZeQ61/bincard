package akin.city_card.buscard.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.buscard.core.request.CreateCardPricingRequest;
import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.response.ResponseMessage;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;

public interface BusCardService {
    ResponseEntity<?> registerCard(RegisterCardRequest req);

    ResponseEntity<?> readCard(String uid);

    ResponseEntity<?> topUpBalance(String uid, BigDecimal bigDecimal);

    ResponseEntity<?> getOn(String uid);

    ResponseMessage createCardPricing(CreateCardPricingRequest createCardPricingRequest, String username) throws AdminNotFoundException;
}
