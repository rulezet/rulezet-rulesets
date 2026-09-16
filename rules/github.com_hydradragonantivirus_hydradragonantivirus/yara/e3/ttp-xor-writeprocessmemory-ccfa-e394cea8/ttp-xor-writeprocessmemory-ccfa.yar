rule TTP_XOR_WriteProcessMemory_ccfa {
  strings:
    $key_ccfa = { 9b 88 [2] a9 aa [2] af 9f [2] 81 9f [2] be 83 }

  condition:
    any of them
}