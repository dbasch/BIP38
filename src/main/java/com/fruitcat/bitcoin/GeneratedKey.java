/**
 *
 * Copyright 2014 Diego Basch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.fruitcat.bitcoin;

/**
 * Convenience container for the key, address, and the confirmation code.
 * If you generated the key yourself, you can disregard the confirmation code.
 */

public class GeneratedKey {
    public final String confirmationCode;
    public final String address;
    public final String key;

    public GeneratedKey(String key, String address, String confirmationCode) {
        this.confirmationCode = confirmationCode;
        this.address = address;
        this.key = key;
    }
}
