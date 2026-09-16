rule TTP_XOR_WriteProcessMemory_67fa {
  strings:
    $key_67fa = { 30 88 [2] 02 aa [2] 04 9f [2] 2a 9f [2] 15 83 }

  condition:
    any of them
}