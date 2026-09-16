rule TTP_XOR_WriteProcessMemory_381a {
  strings:
    $key_381a = { 6f 68 [2] 5d 4a [2] 5b 7f [2] 75 7f [2] 4a 63 }

  condition:
    any of them
}