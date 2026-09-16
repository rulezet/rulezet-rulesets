rule TTP_XOR_WriteProcessMemory_abba {
  strings:
    $key_abba = { fc c8 [2] ce ea [2] c8 df [2] e6 df [2] d9 c3 }

  condition:
    any of them
}