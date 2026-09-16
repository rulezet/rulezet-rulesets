rule TTP_XOR_WriteProcessMemory_afcf {
  strings:
    $key_afcf = { f8 bd [2] ca 9f [2] cc aa [2] e2 aa [2] dd b6 }

  condition:
    any of them
}