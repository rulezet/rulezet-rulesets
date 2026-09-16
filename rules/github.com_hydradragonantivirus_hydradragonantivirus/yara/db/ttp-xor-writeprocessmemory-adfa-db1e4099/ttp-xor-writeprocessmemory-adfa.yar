rule TTP_XOR_WriteProcessMemory_adfa {
  strings:
    $key_adfa = { fa 88 [2] c8 aa [2] ce 9f [2] e0 9f [2] df 83 }

  condition:
    any of them
}