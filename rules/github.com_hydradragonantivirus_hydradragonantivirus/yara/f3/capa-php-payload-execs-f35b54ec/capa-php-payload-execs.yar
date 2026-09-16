rule capa_php_payload_execs: WEBSHELL PROD {
  meta:
    description = "PHP methods for executing OS commands"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
    $xpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
    $xpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
    $xpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
    $xpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
    $xpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
    $xpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
    $xpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii

  condition:
    any of ($xpayload*)
}