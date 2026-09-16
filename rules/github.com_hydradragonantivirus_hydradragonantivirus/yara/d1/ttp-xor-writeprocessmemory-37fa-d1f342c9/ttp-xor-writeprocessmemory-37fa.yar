rule TTP_XOR_WriteProcessMemory_37fa {
  strings:
    $key_37fa = { 60 88 [2] 52 aa [2] 54 9f [2] 7a 9f [2] 45 83 }

  condition:
    any of them
}