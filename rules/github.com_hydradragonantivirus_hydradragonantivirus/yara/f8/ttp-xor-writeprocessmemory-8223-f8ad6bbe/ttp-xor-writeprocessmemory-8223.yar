rule TTP_XOR_WriteProcessMemory_8223 {
  strings:
    $key_8223 = { d5 51 [2] e7 73 [2] e1 46 [2] cf 46 [2] f0 5a }

  condition:
    any of them
}