/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 12077 $ of $ 
 *
 * $Id:$
 */
#ifndef DESSERTAPPPARAMSTABLE_DATA_SET_H
#define DESSERTAPPPARAMSTABLE_DATA_SET_H

#ifdef __cplusplus
extern          "C" {
#endif

    /*
     *********************************************************************
     * SET function declarations
     */

    /*
     *********************************************************************
     * SET Table declarations
     */
/**********************************************************************
 **********************************************************************
 ***
 *** Table dessertAppParamsTable
 ***
 **********************************************************************
 **********************************************************************/
    /*
     * DESSERT-MIB::dessertAppParamsTable is subid 9 of dessertObjects.
     * Its status is Current.
     * OID: .1.3.6.1.4.1.18898.0.19.10.1.1.9, length: 13
     */


    int            
        dessertAppParamsTable_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                         rowreq_ctx);
    int            
        dessertAppParamsTable_undo_cleanup(dessertAppParamsTable_rowreq_ctx
                                           * rowreq_ctx);
    int            
        dessertAppParamsTable_undo(dessertAppParamsTable_rowreq_ctx *
                                   rowreq_ctx);
    int            
        dessertAppParamsTable_commit(dessertAppParamsTable_rowreq_ctx *
                                     rowreq_ctx);
    int            
        dessertAppParamsTable_undo_commit(dessertAppParamsTable_rowreq_ctx
                                          * rowreq_ctx);


    int            
        appParamsName_check_value(dessertAppParamsTable_rowreq_ctx *
                                  rowreq_ctx, char *appParamsName_val_ptr,
                                  size_t appParamsName_val_ptr_len);
    int            
        appParamsName_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                 rowreq_ctx);
    int             appParamsName_set(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx,
                                      char *appParamsName_val_ptr,
                                      size_t appParamsName_val_ptr_len);
    int             appParamsName_undo(dessertAppParamsTable_rowreq_ctx *
                                       rowreq_ctx);

    int            
        appParamsDesc_check_value(dessertAppParamsTable_rowreq_ctx *
                                  rowreq_ctx, char *appParamsDesc_val_ptr,
                                  size_t appParamsDesc_val_ptr_len);
    int            
        appParamsDesc_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                 rowreq_ctx);
    int             appParamsDesc_set(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx,
                                      char *appParamsDesc_val_ptr,
                                      size_t appParamsDesc_val_ptr_len);
    int             appParamsDesc_undo(dessertAppParamsTable_rowreq_ctx *
                                       rowreq_ctx);

    int            
        appParamsValueType_check_value(dessertAppParamsTable_rowreq_ctx *
                                       rowreq_ctx,
                                       u_long appParamsValueType_val);
    int            
        appParamsValueType_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx);
    int             appParamsValueType_set(dessertAppParamsTable_rowreq_ctx
                                           * rowreq_ctx,
                                           u_long appParamsValueType_val);
    int            
        appParamsValueType_undo(dessertAppParamsTable_rowreq_ctx *
                                rowreq_ctx);

    int            
        appParamsTruthValue_check_value(dessertAppParamsTable_rowreq_ctx *
                                        rowreq_ctx,
                                        u_long appParamsTruthValue_val);
    int            
        appParamsTruthValue_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                       rowreq_ctx);
    int            
        appParamsTruthValue_set(dessertAppParamsTable_rowreq_ctx *
                                rowreq_ctx,
                                u_long appParamsTruthValue_val);
    int            
        appParamsTruthValue_undo(dessertAppParamsTable_rowreq_ctx *
                                 rowreq_ctx);

    int            
        appParamsInteger32_check_value(dessertAppParamsTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long appParamsInteger32_val);
    int            
        appParamsInteger32_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                      rowreq_ctx);
    int             appParamsInteger32_set(dessertAppParamsTable_rowreq_ctx
                                           * rowreq_ctx,
                                           long appParamsInteger32_val);
    int            
        appParamsInteger32_undo(dessertAppParamsTable_rowreq_ctx *
                                rowreq_ctx);

    int            
        appParamsUnsigned32_check_value(dessertAppParamsTable_rowreq_ctx *
                                        rowreq_ctx,
                                        u_long appParamsUnsigned32_val);
    int            
        appParamsUnsigned32_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                       rowreq_ctx);
    int            
        appParamsUnsigned32_set(dessertAppParamsTable_rowreq_ctx *
                                rowreq_ctx,
                                u_long appParamsUnsigned32_val);
    int            
        appParamsUnsigned32_undo(dessertAppParamsTable_rowreq_ctx *
                                 rowreq_ctx);

    int            
        appParamsOctetString_check_value(dessertAppParamsTable_rowreq_ctx *
                                         rowreq_ctx,
                                         char
                                         *appParamsOctetString_val_ptr,
                                         size_t
                                         appParamsOctetString_val_ptr_len);
    int            
        appParamsOctetString_undo_setup(dessertAppParamsTable_rowreq_ctx *
                                        rowreq_ctx);
    int            
        appParamsOctetString_set(dessertAppParamsTable_rowreq_ctx *
                                 rowreq_ctx,
                                 char *appParamsOctetString_val_ptr,
                                 size_t appParamsOctetString_val_ptr_len);
    int            
        appParamsOctetString_undo(dessertAppParamsTable_rowreq_ctx *
                                  rowreq_ctx);


    int            
        dessertAppParamsTable_check_dependencies
        (dessertAppParamsTable_rowreq_ctx * ctx);


#ifdef __cplusplus
}
#endif
#endif                          /* DESSERTAPPPARAMSTABLE_DATA_SET_H */