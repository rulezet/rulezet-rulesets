rule DodgyPhp
{
    meta:
        source = "https://github.com/nbs-system/php-malware-finder"
        
    strings:
        $basedir_bypass = /curl_init\s*\(\s*["']file:\/\// nocase
        $basedir_bypass2 = "file:file:///"         $disable_magic_quotes = /set_magic_quotes_runtime\s*\(\s*0/ nocase

        $execution = /\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase          $execution2 = /\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase          $execution3 = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff)\s*\(\s*([^,]+\s*,?)+\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))\s*\[[^]]+\]\s*\)+\s*;/ nocase  
        $htaccess = "SetHandler application/x-httpd-php"
        $iis_com = /IIS:\/\/localhost\/w3svc/
        $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/          $ini_get = /ini_(get|set|restore)\s*\(\s*['"](safe_mode|open_basedir|disable_(function|classe)s|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase
        $register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/          $safemode_bypass = /\x00\/\.\.\/|LD_PRELOAD/
        $shellshock = /\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/
        $udp_dos = /fsockopen\s*\(\s*['"]udp:\/\// nocase
        $various = "<!--#exec cmd="          $at_eval = /@eval\s*\(/ nocase
        $double_var = /\${\s*\${/
        $extract = /extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/
        $reversed = /noitcnuf_etaerc|metsys|urhtssap|edulcni|etucexe_llehs/ nocase
                $silenced_include =/@\s*include\s*/ nocase

    condition:
        (any of them)
}