rule backdoor_o9g {
  meta:
    description = "work1 - file backdoor_o9g.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "1bbe577ace2c701cad8617f94aac5723f929a21d9d703d64f108934dc97ccd8e"

  strings:
    $s1  = "9nWowmdq+1bZOfNUrtsNot+QHK8q+zHVFYDno6zPcrzO4arJ77kThps5PhFP9LR+mu/LaHuwz9aO3avxs2T3g65417hqc4XqbZGkrQf4LOgPYHNYDMZ8R0vU1TdoSyxA" ascii
    $s2  = "echo                                                                                                               " fullword ascii
    $s3  = "$__=                                                              'base64_decode'                           ;  " fullword ascii
    $s4  = "$__________=$__________________('$_',$______________);                                                                  " fullword ascii
    $s5  = "$_____='    b2JfZW5kX2NsZWFu';                                                                                          " fullword ascii
    $s6  = "5Offk7/++/dHXi+8e8+Lf8s7/PsX/P/L/8u6zUb+X798/rv975dznP79bBIpSv/79/8PuOX90w==';" fullword ascii
    $s7  = "A9tR6iNmkzWYva/COmN90AGzs1aSWGsxZyI5z1aieSx4hvEQ9/DCcy/9lNYLzwk+0H2WB1vO8UjoNsmjIbKHzAORmTRv4hJemX12FnQv0RKsZJ78zpSxG3k+bgV82fm7" ascii
    $s8  = "xwszuFc+tDGykz4bxpxP4O52ER5D0WSB6X7TtzieEcCzBZi7J4SFhXEcmdG7MU3ubQDezayFf0NbS32XzbEDvIs/Ed6S4BbnpBu/BAxQPeDnK7xvzHgxRrzAmF+g3zb+" ascii
    $s9  = "jL+I051je0GfQXkrpLJh9doPCzRUnrvo8JrjF2X/zmnjd+H6fKzkA/NmTV+vjtMCuaNOdBNkaaRfG6uF79qM1DHMZ7M43lf9bLyUvw6eUfYAT5CWTj8A2LWTY+uYioL9" ascii
    $s10 = "3o1+XWs64oKg4P94kI81r+WiJPGnQ97GQ/p0BW8KftY8gpwk+usd/uOCLeQurY3bemS9VPihrunVFf3e4GFVOuQNv1EGy5nPzOZUdjw8hqADHH3gS75EYogXvlavkLuW" ascii
    $s11 = "$____='b2JfZ2V0X2NvbnRlbnRz';                                                                               " fullword ascii
    $s12 = "$___();$__________($______($__($_))); $________=$____();" fullword ascii

  condition:
    (uint16(0) == 0x3c0a and
      filesize < 70KB and
      (8 of them)
    ) or (all of them)
}