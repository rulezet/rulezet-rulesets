rule RijnDael_AES_RCON {
  meta:
    author      = "edeca"
    description = "RijnDael AES round constants"
    date        = "2019-10"

  strings:
    $c0 = { 8D 01 02 04 08 10 20 40 80 1B 36 6C D8 AB 4D 9A }

  condition:
    $c0
}