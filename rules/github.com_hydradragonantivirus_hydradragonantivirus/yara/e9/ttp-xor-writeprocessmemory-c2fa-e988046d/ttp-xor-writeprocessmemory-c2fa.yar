rule TTP_XOR_WriteProcessMemory_c2fa {
  strings:
    $key_c2fa = { 95 88 [2] a7 aa [2] a1 9f [2] 8f 9f [2] b0 83 }

  condition:
    any of them
}