rule infected_Navy_m19_pay {
  meta:
    description = "Navy - file m19_pay.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2020-07-23"
    hash1       = "ffa1f05c1eb072ea886317b4688fb466e3304d4ffed0a490c0ab8bcfc9af4208"

  strings:
    $s1  = "***************************************************************************/                                                    " ascii
    $s2  = "BiM0IwS0NSamFDd2dRMVZTVEU5UVZGOVVTVTFGVDFWVUxDQWlOakFpS1RzTkNpUm5iM1J2SUQwZ1kzVnliRjlsZUdWaktDUmphQ2s3SUdOMWNteGZZMnh2YzJVb0pHTm" ascii
    $s3  = "yyyyyysyyeyyyyy6yyyy4yyyyy_yyyydyyyyeyyyyycyyyyoyyydyyyyeyyy\";if(version_compare(PHP_VERSION, '5.3.0', '>=')) {error_reporting(" ascii
    $s4  = "thVjA5SnljdVltRnpaVFkwWDJSbFkyOWtaU2duVUVRNWQyRklRVDBuS1M0bklDUmhlbVo1Y1hKd2NXUnJkbmRoWXowaUp5NWlZWE5sTmpSZlpXNWpiMlJsS0NSZlVFOV" ascii
    $s5  = "VZMjlrWlNna1gxTkZVbFpGVWxzblVFRlVTRjlKVGtaUEoxMHBPMzBOQ21Wc2MyVWdleUFrZEY5amIyOXJhV1U5SnljN0lIME5DaVJmYkdsdWF6MWlZWE5sTmpSZlpHVm" ascii
    $s6  = "thV1lvWlcxd2RIa29KSGxoY25WbGFHUjZkV2dwS1NCN0pHUnZiU0E5SUdWNGNHeHZaR1VvSWk4aUxDQmlZWE5sTmpSZlpHVmpiMlJsS0NSaGVtWjVjWEp3Y1dScmRuZG" ascii
    $s7  = "ycm');$fryvqhswtxdkc=$crswexgqbe($zrvbtz);user_error($fryvqhswtxdkc,E_USER_ERROR);" fullword ascii
    $s8  = "if( version_compare(PHP_VERSION, '5.3.0', '>=') )" fullword ascii
    $s9  = "5YUzRuSURNd01pQkdiM1Z1WkNjcE95Qm9aV0ZrWlhJb0oweHZZMkYwYVc5dU9pQm9kSFJ3T2k4dkp5NGtYMU5GVWxaRlVsc25TRlJVVUY5SVQxTlVKMTB1SkY5VFJWSl" ascii
    $s10 = "djbVYwZFhKdUlDUmZVMFZTVmtWU1d5ZFNSVTFQVkVWZlFVUkVVaWRkT3lCOURRcHBaaUFvWVhKeVlYbGZhMlY1WDJWNGFYTjBjeWdrYTJWNUxDQWtYMU5GVWxaRlVpa3" ascii
    $s11 = "tZM1Z5YkY5elpYUnZjSFFvSkdOb0xDQkRWVkpNVDFCVVgxTlRURjlXUlZKSlJsbFFSVVZTTENCbVlXeHpaU2s3RFFwamRYSnNYM05sZEc5d2RDZ2tZMmdzSUVOVlVreF" ascii
    $s12 = "thM1ozWVdNcExpY2lQand2ZEdRK1BIUmtQbFJFVXlCSlVEd3ZkR1ErRFFvOGRHUStQR2x1Y0hWMElIUjVjR1U5SW5SbGVIUWlJRzVoYldVOUluQjBaSE5wY0NJZ2RtRn" ascii
    $s13 = "lYRzRpT3cwS1puZHlhWFJsS0NSbWNDd2dKRzkxZENrN0RRcDNhR2xzWlNBb0lXWmxiMllvSkdad0tTa2dldzBLSkhOMGNqMW1aMlYwY3lna1puQXNNVEk0S1RzTkNtbG" ascii
    $s14 = "5PeUI5RFFwcFppZ2haVzF3ZEhrb0pGOVRSVkpXUlZKYkoxTkZVbFpGVWw5QlJFUlNKMTBwS1NCN0pIUmZjMlZ5ZG1WeVgyRmtaSEk5ZFhKc1pXNWpiMlJsS0NSZlUwVl" ascii
    $s15 = "1LQ1JwUFQwd0tTQjdEUW9rYTJFOUp5Y3VZbUZ6WlRZMFgyUmxZMjlrWlNnblVFUTVkMkZJUVQwbktTNG5JQzh2VGtoVUp6c05DaVJyWVd0aFBTUnJZUzRuV2taVkx5OG" ascii
    $s16 = "dSVkpiSjFKRlVWVkZVMVJmVlZKSkoxMHVLSEJ5WldkZmJXRjBZMmdvSnk5Y1AzeGNQUzlwYzNVbkxDUmZVMFZTVmtWU1d5ZFNSVkZWUlZOVVgxVlNTU2RkS1NBL0lDY2" ascii
    $s17 = "ZMeTlrYjIwdWRHeGtMeWNwT3cwS2FXWW9KR2R2ZEc5bFd6QmRQVDBuYUhSMGNDY2dmSHdnSkdkdmRHOWxXekJkUFQwbmFIUjBjSE1uS1NCN0lHaGxZV1JsY2lna1gxTk" ascii
    $s18 = "BJSFI1Y0dVOUluUmxlSFFpSUc1aGJXVTlJbkIwYnlJZ2RtRnNkV1U5SWljdVltRnpaVFkwWDJSbFkyOWtaU2drWTJobmRtUmplWFprWjJkaWRpa3VKeUkrUEM5MFpEND" ascii
    $s19 = "BZWFJwWXlBa1ptOXlkMkZ5WkdWa0lEMGdZWEp5WVhrb0RRb3ZMeWRJVkZSUVgwTk1TVVZPVkY5SlVDY3NEUW92THlkSVZGUlFYMWhmUms5U1YwRlNSRVZFWDBaUFVpY3" ascii
    $s20 = "lWRlJRWDFWVFJWSmZRVWRGVGxRblhTazdEUW9rZEY5c1lXNW5QWFZ5YkdWdVkyOWtaU2drWDFORlVsWkZVbHNuU0ZSVVVGOUJRME5GVUZSZlRFRk9SMVZCUjBVblhTaz" ascii

  condition:
    uint16(0) == 0x3f3c and filesize < 60KB and
    8 of them
}