rule dump_sales_quote_payment {
    strings: $ = "include '../../../../../../../../../../app/Mage.php'; Mage::app(); $q = Mage::getModel('sales/quote_payment')->getCollection();"
    condition: any of them
}