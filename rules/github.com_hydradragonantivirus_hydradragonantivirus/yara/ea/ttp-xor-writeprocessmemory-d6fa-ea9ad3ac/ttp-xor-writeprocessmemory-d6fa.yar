rule TTP_XOR_WriteProcessMemory_d6fa {
  strings:
    $key_d6fa = { 81 88 [2] b3 aa [2] b5 9f [2] 9b 9f [2] a4 83 }

  condition:
    any of them
}