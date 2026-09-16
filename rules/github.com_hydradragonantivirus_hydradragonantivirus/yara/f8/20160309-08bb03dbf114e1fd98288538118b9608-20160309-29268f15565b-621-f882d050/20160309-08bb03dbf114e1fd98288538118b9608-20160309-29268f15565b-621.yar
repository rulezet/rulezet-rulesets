rule _20160309_08bb03dbf114e1fd98288538118b9608_20160309_29268f15565b_621 {
  meta:
    description = "datamaliciousorder - from files 20160309_08bb03dbf114e1fd98288538118b9608.js, 20160309_29268f15565bbec406f279967916aaba.js, 20160309_2950890034dcc05ca33c0292b89d70a0.js, 20160309_434f80fe4b5e1117ed4a55d6e65377e4.js, 20160309_4e45fcf671e8d6aca50a3ee13ecbea65.js, 20160309_5775369f35acc4f2b5e485095e61c4eb.js, 20160309_620ab01c5fcd66152167219ae02d8cf0.js, 20160309_89642c6d6ce0223ac270a7500a1ecd25.js, 20160309_8b0690ae4a5416b2fca0f906ea1b4d12.js, 20160309_8dbb1c66e38ede6822f5193bdef84916.js, 20160309_97948381c31e0f7f4d6551367d0e5a1f.js, 20160309_97c35a1a9d558418080fd1afac98854a.js, 20160309_aa5339ff5a2f0b9fe812742d05a47e78.js, 20160309_d0da6b76d23b9b327484d343e881a30a.js, 20160309_dfc88e3d7946e2d28b06473b8baff8a3.js, 20160309_f0c6d1b5439bf3e4917a86f9e6b54b76.js, 20160309_f2990b202447a8dd3617768da4bfa8c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8777ce87b61c299c4dc772bde6a5ba8a7d060443efa434cad7de00ebdc582411"
    hash2       = "a7057964ba8b973e18728545a23b1cf360d75964ae601f89bfd8bb347b4181c6"
    hash3       = "d1bd63759483b68e2aae813f9738734155ee81fd0fa32e1275dd8212f917aa78"
    hash4       = "3738ccf6edd3365cb525bdb45b2e3630ba414befdbdb96398eedb916402496c6"
    hash5       = "04bfdfdb199d3bae6e6bd5eaf321c5978aab9a77ea9ba7f57e36b3749a26de50"
    hash6       = "6c52880bb9b1f1899542501fc98827c3ffedb85fc9cdef9005c3c2c8149c851c"
    hash7       = "c5ce0ad79e966fb4e5ce69bd29cfc3dcba81ebc11e6dd33d3860854d95b28867"
    hash8       = "5d544f35fd590d9f93a9f3140fd3cb8050e053755a09f58ad780d3e0a5d21d62"
    hash9       = "f916bd091c0de5a40122646f9d10074c9e434003d796e0285ed658640323e0e6"
    hash10      = "6ec71084b943a3b9398751b42f2181bcf4a96fc8cf3ecf137f1d477ff4f71b82"
    hash11      = "0aa3961ae5634bde74bfe8e747194196a0f9b6e3f9d1a0f3dc5d232a1041d91b"
    hash12      = "8ef9080c27a91f307a90cf3c131b1657694d76a9528a4d21271da2bfb913d918"
    hash13      = "5953b5105f0f193bd7534136b831daa848878932575cbb8449c4777ed4057181"
    hash14      = "591706ce5ddd8fbac1f536dea99d008422f2ccb456895064a1cd6619ba7c8a3b"
    hash15      = "e89dd5802715f1af864e21660a4c0050c4e6637e459ede486fc3dbf8c2b410e0"
    hash16      = "b4257663ae30c574fbed1907febadb92c70a2a3d027bc342a6e0127ea6296f9d"
    hash17      = "e5c126332dc34e9c84ce95228bb2d25a95e6a65f15476c6cf11b9e02b10f144b"

  strings:
    $s1  = "   (such as loading iframes in IE - #4833)  var documentElement = elem && (elem.ownerDocument || elem).documentElement;  return " ascii
    $s2  = "        //  Support: IE 9-11, Edge   Accessing iframe documents after unload throws \\\"permission denied\\\" errors (jQuery #13" ascii
    $s3  = "        //  Check if getElementsByTagName(\\\"*\\\") returns only elements  support.getElementsByTagName = assert(function( div " ascii
    $s4  = "        //   Support: IE 9 - 10 only   } else if ( parent.attachEvent ) {    parent.attachEvent( \\\"onunload\\\", unloadHandler" ascii
    $s5  = "        //   Support: IE 9 - 10 only   } else if ( parent.attachEvent ) {    parent.attachEvent( \\\"onunload\\\", unloadHandler" ascii
    $s6  = "    var node = typeof elem.getAttributeNode !== \\\"undefined\\\" &&      elem.getAttributeNode(\\\"id\\\");     return node && " ascii
    $s7  = "///**  * Detects XML nodes  * @param {Element|Object} elem An element or a document  * @returns {Boolean} True iff elem is a non" ascii
    $s8  = "    //  ID find and filter  if ( support.getById ) {   Expr.find[\\\"ID\\\"] = function( id, context ) {    if ( typeof context." ascii
    $s9  = "///**  * Detects XML nodes  * @param {Element|Object} elem An element or a document  * @returns {Boolean} True iff elem is a non" ascii
    $s10 = "  if ( (parent = document.defaultView) && parent.top !== parent ) {    Support: IE 11   if ( parent.addEventListener ) {    pare" ascii
    $s11 = "ent object to use to set the document  * @returns {Object} Returns the current document  */ setDocument = Sizzle.setDocument = f" ascii
    $s12 = "///**  * Sets document-related variables once based on the current document  * @param {Element|Object} [doc] An element or docum" ascii
    $s13 = "//}  Tag  Expr.find[\\\"TAG\\\"] = support.getElementsByTagName ?   function( tag, context ) {    if ( typeof context.getElement" ascii
    $s14 = "//} Expose support vars for convenience support = Sizzle.support = {};" fullword ascii
    $s15 = "        //  Support: IE<8   Verify that getAttribute really returns attributes and not properties   (excepting IE8 booleans)  su" ascii
    $s16 = "        //  Check if getElementsByTagName(\\\"*\\\") returns only elements  support.getElementsByTagName = assert(function( div " ascii
    $s17 = "nt.addEventListener( \\\"unload\\\", unloadHandler, false );" fullword ascii
    $s18 = "//}  Tag  Expr.find[\\\"TAG\\\"] = support.getElementsByTagName ?   function( tag, context ) {    if ( typeof context.getElement" ascii
    $s19 = "lementById !== \\\"undefined\\\" && documentIsHTML ) {     var m = context.getElementById( id );     return m ? [ m ] : [];    }" ascii
    $s20 = "    //  Support: IE<10   Check if getElementById returns elements by name   The broken getElementById methods don\\\"t pick up p" ascii

  condition:
    (uint16(0) == 0x2f2f and (8 of them)
    ) or (all of them)
}