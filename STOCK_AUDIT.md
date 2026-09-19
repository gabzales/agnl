# Stock / Provider Root Audit — v24

## What was re-checked
- LIVE stock is provider capacity: `floor(balance / variant price)` using integer cents.
- HYBRID stock is local exact-duration stock + provider capacity for the same mapped variant.
- LOCAL ignores provider.
- Product availability is based on the maximum purchasable option, not the sum of all durations.
- Provider mapping is exact duration + unit plus explicit aliases; broad fuzzy matching is not used.
- Sync/auto-map never calls `generate_key.php`.
- Actual provider purchase is only in fulfillment after payment (or explicit admin restock approval).
- Purchase is guarded by a persistent purchase lock and a fresh balance + price check.
- Cache is fail-closed after TTL; expired provider data is never used as a stock fallback.
- Homepage/admin cold-start provider fetch gets enough time to complete the provider snapshot.
- Homepage has one bulk stock refresh endpoint instead of one provider-backed request per product card.
- Public stock refresh endpoints are rate-limited and never expose local keys.
- Buy-page refresh still verifies each option and keeps the selected JS stock in sync.

## Remaining operational requirement
After deployment, set the DripStore API token/base URL in Settings and keep `fulfillmentMode=live` if the intended behavior is JIT provider fulfillment. Do not click restock/approve just to test catalog stock.
