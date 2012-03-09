/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 14170 $ of $
 *
 * $Id:$
 */
#ifndef DESSERTMESHIFTABLE_DATA_ACCESS_H
#define DESSERTMESHIFTABLE_DATA_ACCESS_H

#include "dessert_internal.h"

#ifdef __cplusplus
extern          "C" {
#endif


    /*
     *********************************************************************
     * function declarations
     */

    /*
     *********************************************************************
     * Table declarations
     */
/**********************************************************************
 **********************************************************************
 ***
 *** Table dessertMeshifTable
 ***
 **********************************************************************
 **********************************************************************/
    /*
     * DESSERT-MIB::dessertMeshifTable is subid 5 of dessertObjects.
     * Its status is Current.
     * OID: .1.3.6.1.4.1.18898.0.19.10.1.1.5, length: 12
     */


    int            
        dessertMeshifTable_init_data(dessertMeshifTable_registration *
                                     dessertMeshifTable_reg);


    /*
     * TODO:180:o: Review dessertMeshifTable cache timeout.
     * The number of seconds before the cache times out
     */
#define DESSERTMESHIFTABLE_CACHE_TIMEOUT   DESSERT_AGENTX_MESHIFTABLE_CACHE_TIMEOUT

    void            dessertMeshifTable_container_init(netsnmp_container **
                                                      container_ptr_ptr,
                                                      netsnmp_cache *
                                                      cache);
    void            dessertMeshifTable_container_shutdown(netsnmp_container
                                                          * container_ptr);

    int             dessertMeshifTable_container_load(netsnmp_container *
                                                      container);
    void            dessertMeshifTable_container_free(netsnmp_container *
                                                      container);

    int             dessertMeshifTable_cache_load(netsnmp_container *
                                                  container);
    void            dessertMeshifTable_cache_free(netsnmp_container *
                                                  container);

    int            
        dessertMeshifTable_row_prep(dessertMeshifTable_rowreq_ctx *
                                    rowreq_ctx);



#ifdef __cplusplus
}
#endif
#endif                          /* DESSERTMESHIFTABLE_DATA_ACCESS_H */