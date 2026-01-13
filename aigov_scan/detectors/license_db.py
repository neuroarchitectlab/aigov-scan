from __future__ import annotations

LICENSE_SIGNALS: dict[str, list[str]] = {
    "Apache-2.0": [
        "apache license",
        "version 2.0",
        "http://www.apache.org/licenses/",
        "apache software foundation"
    ],
    "MIT": [
        "permission is hereby granted, free of charge",
        "the software is provided \"as is\"",
        "mit license"
    ],
    "BSD-3-Clause": [
        "redistribution and use in source and binary forms",
        "neither the name of",
        "bsd 3-clause"
    ],
    "GPL-3.0-only": [
        "gnu general public license",
        "either version 3 of the license",
        "gplv3"
    ],
    "CC-BY-4.0": [
        "creative commons attribution 4.0",
        "cc-by-4.0",
        "creativecommons.org/licenses/by/4.0"
    ],
    "CC-BY-SA-4.0": [
        "creative commons attribution-sharealike 4.0",
        "cc-by-sa-4.0",
        "creativecommons.org/licenses/by-sa/4.0"
    ],
    "CC-BY-NC-4.0": [
        "creative commons attribution-noncommercial 4.0",
        "cc-by-nc-4.0",
        "creativecommons.org/licenses/by-nc/4.0"
    ],
}

MIN_CONFIDENCE = 0.6
