rule TTP_XOR_WriteProcessMemory_adea {
  strings:
    $key_adea = { fa 98 [2] c8 ba [2] ce 8f [2] e0 8f [2] df 93 }

  condition:
    any of them
}