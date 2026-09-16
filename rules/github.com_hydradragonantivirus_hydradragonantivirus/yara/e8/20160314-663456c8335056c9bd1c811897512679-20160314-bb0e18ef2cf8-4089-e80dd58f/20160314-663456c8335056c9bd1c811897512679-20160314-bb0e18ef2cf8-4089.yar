rule _20160314_663456c8335056c9bd1c811897512679_20160314_bb0e18ef2cf8_4089 {
  meta:
    description = "datamaliciousorder - from files 20160314_663456c8335056c9bd1c811897512679.js, 20160314_bb0e18ef2cf8dfe4f63e00a519a008ce.js, 20160314_cb1abde51592f9f8346206d76c823bde.js, 20160314_ead88e3c2b69b673ca9df8732a329c28.js, 20160315_a187eaaea5ce445a9af771cf48ec181f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "714495d8a2235f0c41a06c2452c03f827686a6206864cb7953c64b5c4c3cfb02"
    hash2       = "0f6490f925fc0997a979fa732729f967331775e32340356ea75ac01011133a60"
    hash3       = "f57f0427e2eee16c0b2fc425eaf82689fd64244bf8eff04a9f6b2711cc435ec2"
    hash4       = "0fed0548c60e0dcf85e21d9cb315069b170b2644c9d6aee3a4ec7a50ff7e556c"
    hash5       = "a39014f56f8c0dd22605247cb3cb42a7f7ffc282e97cda380f437703e8cbfcbf"

  strings:
    $s1 = "lem.nodeValue;  }   Do not include comment or processing instruction nodes\";" fullword ascii
    $s2 = "o not traverse comment nodes    ret += getText( node );   }  } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) {" ascii
    $s3 = "    Use textContent for elements    innerText usage removed for consistency of new lines (jQuery #11153)   if ( typeof elem.text" ascii
    $s4 = "Content === \\\"string\\\" ) {    return elem.textContent;   } else {     Traverse its children    for ( elem = elem.firstChild;" ascii
    $s5 = "m; elem = elem.nextSibling ) {     ret += getText( elem );    }   }  } else if ( nodeType === 3 || nodeType === 4 ) {   return e" ascii

  condition:
    ((uint16(0) == 0x7457 or uint16(0) == 0x7969 or uint16(0) == 0x7474 or uint16(0) == 0x5476 or uint16(0) == 0x777a) and (all of them)
    ) or (all of them)
}