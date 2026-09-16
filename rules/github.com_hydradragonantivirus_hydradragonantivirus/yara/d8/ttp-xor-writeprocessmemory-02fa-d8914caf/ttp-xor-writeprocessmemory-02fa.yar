rule TTP_XOR_WriteProcessMemory_02fa {
  strings:
    $key_02fa = { 55 88 [2] 67 aa [2] 61 9f [2] 4f 9f [2] 70 83 }

  condition:
    any of them
}