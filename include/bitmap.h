#ifndef __BIT_MAP_H__
#define __BIT_MAP_H__

#define BIT_MAP_ITER_LSH	6
#define BIT_MAP_SEG_LSH		5
#define BIT_MAP_TOP_LSH		(BIT_MAP_ITER_LSH + BIT_MAP_SEG_LSH)

#define PORT_NUM 			65536
#define BIT_MAP_PER_ITEM	(1 << BIT_MAP_ITER_LSH)
#define BIT_MAP_ITEM_NUM	(PORT_NUM/BIT_MAP_PER_ITEM)
#define BIT_MAP_PER_SEG		(1 << BIT_MAP_SEG_LSH)
#define BIT_MAP_SEG_NUM		(BIT_MAP_ITEM_NUM/BIT_MAP_PER_SEG)

#define item_index(top,mid)	((top)*BIT_MAP_PER_SEG + (mid))

struct bitmap_s{
	uint32_t top_index;
	uint32_t mid_index[BIT_MAP_PER_SEG];
	uint64_t bit_map[BIT_MAP_ITEM_NUM];
};

struct bitmap_s *bitmap_init(struct bitmap_s *bmap);

void set_bitmap(struct bitmap_s *lbmap, uint16_t u16_test);
void clear_bitmap(struct bitmap_s *lbmap, uint16_t u16_test);
void check_bitmap(struct bitmap_s *lbmap);
int get_free_num(struct bitmap_s *lbmap, uint32_t begin, uint16_t *result);

#endif
