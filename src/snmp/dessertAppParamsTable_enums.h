/*
 * Note: this file originally auto-generated by mib2c using
 *  : generic-table-enums.m2c 12526 2005-07-15 22:41:16Z rstory $
 *
 * $Id:$
 */
#ifndef DESSERTAPPPARAMSTABLE_ENUMS_H
#define DESSERTAPPPARAMSTABLE_ENUMS_H

#ifdef __cplusplus
extern          "C" {
#endif

    /*
     * NOTES on enums
     * ==============
     *
     * Value Mapping
     * -------------
     * If the values for your data type don't exactly match the
     * possible values defined by the mib, you should map them
     * below. For example, a boolean flag (1/0) is usually represented
     * as a TruthValue in a MIB, which maps to the values (1/2).
     *
     */
/*************************************************************************
 *************************************************************************
 *
 * enum definitions for table dessertAppParamsTable
 *
 *************************************************************************
 *************************************************************************/

/*************************************************************
 * constants for enums for the MIB node
 * appParamsValueType (DessertAppValueType / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef DESSERTAPPVALUETYPE_ENUMS
#define DESSERTAPPVALUETYPE_ENUMS

#define DESSERTAPPVALUETYPE_BOOL  0
#define DESSERTAPPVALUETYPE_INT32  1
#define DESSERTAPPVALUETYPE_UINT32  2
#define DESSERTAPPVALUETYPE_COUNTER64  3
#define DESSERTAPPVALUETYPE_OCTETSTRING  4

#endif                          /* DESSERTAPPVALUETYPE_ENUMS */

    /*
     * TODO:140:o: Define your interal representation of appParamsValueType enums.
     * (used for value mapping; see notes at top of file)
     */
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSVALUETYPE_BOOL          DESSERT_APPPARAMS_VALUETYPE_BOOL
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSVALUETYPE_INT32         DESSERT_APPPARAMS_VALUETYPE_INT32
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSVALUETYPE_UINT32        DESSERT_APPPARAMS_VALUETYPE_UINT32
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSVALUETYPE_COUNTER64     DESSERT_APPPARAMS_VALUETYPE_COUNTER64
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSVALUETYPE_OCTETSTRING   DESSERT_APPPARAMS_VALUETYPE_OCTETSTRING


/*************************************************************
 * constants for enums for the MIB node
 * appParamsTruthValue (TruthValue / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef TRUTHVALUE_ENUMS
#define TRUTHVALUE_ENUMS

#define TRUTHVALUE_TRUE   1
#define TRUTHVALUE_FALSE  2

#endif                          /* TRUTHVALUE_ENUMS */

    /*
     * TODO:140:o: Define your interal representation of appParamsTruthValue enums.
     * (used for value mapping; see notes at top of file)
     */
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSTRUTHVALUE_TRUE  DESSERT_APPPARAMS_BOOL_TRUE
#define INTERNAL_DESSERTAPPPARAMSTABLE_APPPARAMSTRUTHVALUE_FALSE DESSERT_APPPARAMS_BOOL_FALSE




#ifdef __cplusplus
}
#endif
#endif                          /* DESSERTAPPPARAMSTABLE_ENUMS_H */