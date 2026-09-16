rule TTP_XOR_WriteProcessMemory_b4fa {
  strings:
    $key_b4fa = { e3 88 [2] d1 aa [2] d7 9f [2] f9 9f [2] c6 83 }

  condition:
    any of them
}