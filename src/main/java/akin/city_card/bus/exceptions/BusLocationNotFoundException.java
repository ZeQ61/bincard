package akin.city_card.bus.exceptions;

import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.security.exception.BusinessException;

public class BusLocationNotFoundException extends BusinessException {
    public BusLocationNotFoundException( ) {
        super("otobus konum verisi bulunamadı");
    }
}
