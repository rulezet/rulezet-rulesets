rule TTP_XOR_WriteProcessMemory_bdfa {
  strings:
    $key_bdfa = { ea 88 [2] d8 aa [2] de 9f [2] f0 9f [2] cf 83 }

  condition:
    any of them
}