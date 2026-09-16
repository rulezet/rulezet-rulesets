rule TTP_XOR_WriteProcessMemory_9fcf {
  strings:
    $key_9fcf = { c8 bd [2] fa 9f [2] fc aa [2] d2 aa [2] ed b6 }

  condition:
    any of them
}