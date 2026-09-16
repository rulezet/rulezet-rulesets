rule TTP_XOR_WriteProcessMemory_64fa {
  strings:
    $key_64fa = { 33 88 [2] 01 aa [2] 07 9f [2] 29 9f [2] 16 83 }

  condition:
    any of them
}