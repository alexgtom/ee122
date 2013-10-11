1. Alexander Tom (ee122-ki)
2. The challenge I faced was implementing poison reverse and implicit withdrawals.
3. An improvment would be to queue up the RoutingUpdates, aggregate the distance
   table, and condense them into a less number of RoutingUpdates that need to be
   sent out. That way, we reduce the number of RoutingUpdates that need to be sent
   and therefore the DV algorithm converges faster.
4. No extra credit implemented
