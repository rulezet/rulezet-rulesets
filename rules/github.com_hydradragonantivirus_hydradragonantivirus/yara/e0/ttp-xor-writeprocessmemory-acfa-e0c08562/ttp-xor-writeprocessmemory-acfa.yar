rule TTP_XOR_WriteProcessMemory_acfa {
  strings:
    $key_acfa = { fb 88 [2] c9 aa [2] cf 9f [2] e1 9f [2] de 83 }

  condition:
    any of them
}