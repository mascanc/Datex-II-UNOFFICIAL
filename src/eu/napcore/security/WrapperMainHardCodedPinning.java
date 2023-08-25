package eu.napcore.security;

import java.lang.reflect.Field;

public class WrapperMainHardCodedPinning {

	public static void main (String[] args) {
		
		/*
		 * Instantiate the decompiled class
		 */
		Object main = new MainHardCodedPinning();
		
		Field[] fields = main.getClass().getDeclaredFields();
		try {
			/*
			 * Change the fields and the certificate value
			 */
			fields[1].setAccessible(true);
			fields[1].set(main, "Wrong");
		} catch (IllegalArgumentException | IllegalAccessException e) {
			throw new IllegalStateException(e);
		};
		((MainHardCodedPinning)main).main(null);
		
	}

}
