rule TTP_XOR_WriteProcessMemory_eccf {
  strings:
    $key_eccf = { bb bd [2] 89 9f [2] 8f aa [2] a1 aa [2] 9e b6 }

  condition:
    any of them
}