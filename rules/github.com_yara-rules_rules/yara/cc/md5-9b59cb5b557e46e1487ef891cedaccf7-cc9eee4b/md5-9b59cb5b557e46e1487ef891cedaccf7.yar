rule md5_9b59cb5b557e46e1487ef891cedaccf7 {
    strings: 
        $jpg = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 01 }
		
        $php = "<?php"
    condition: ($jpg at 0) and $php
}