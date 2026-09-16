rule TTP_XOR_WriteProcessMemory_521a {
  strings:
    $key_521a = { 05 68 [2] 37 4a [2] 31 7f [2] 1f 7f [2] 20 63 }

  condition:
    any of them
}