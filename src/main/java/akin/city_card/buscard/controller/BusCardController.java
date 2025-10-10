package akin.city_card.buscard.controller;

import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.service.abstracts.BusCardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/buscard")
@RequiredArgsConstructor
public class BusCardController {
    private final BusCardService busCardService;

    @PostMapping("/register")
    public ResponseEntity<?> registerCard(@RequestBody RegisterCardRequest req) {
        return busCardService.registerCard(req);
    }

    @PostMapping("/read")
    public ResponseEntity<?> readCard(@RequestBody Map<String, String> request) {
        try {
            String uid = request.get("uid");
            if (uid == null || uid.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
            }

            return busCardService.readCard(uid);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }


    //bakiye yükleme
    @PostMapping("/top-up")
    public ResponseEntity<?> topUpBalance(@RequestBody Map<String, Object> request) {

        String uid = (String) request.get("uid");
        Number amount = (Number) request.get("amount");
        return busCardService.topUpBalance(uid, BigDecimal.valueOf(amount.doubleValue()));

    }

    // get-on / biniş işlemi
    @PostMapping("/get-on")
    public ResponseEntity<?> getOn(@RequestBody Map<String, String> request) {
        try {
            String uid = request.get("uid");

            if (uid == null || uid.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
            }

            return busCardService.getOn(uid);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }


}
