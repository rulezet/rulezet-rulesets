rule TTP_XOR_WriteProcessMemory_52fa {
  strings:
    $key_52fa = { 05 88 [2] 37 aa [2] 31 9f [2] 1f 9f [2] 20 83 }

  condition:
    any of them
}