rule TTP_XOR_WriteProcessMemory_cacf {
  strings:
    $key_cacf = { 9d bd [2] af 9f [2] a9 aa [2] 87 aa [2] b8 b6 }

  condition:
    any of them
}