package com.sa.event_mng.faker;

import com.sa.event_mng.model.entity.Category;
import com.sa.event_mng.repository.CategoryRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CategorySeeder {

    private final CategoryRepository categoryRepository;

    public CategorySeeder(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    public void seed() {
        if (categoryRepository.count() > 0) return;

        List<Category> categories = new ArrayList<>();

        categories.add(createCategory("Âm nhạc", "Các sự kiện âm nhạc, concert, acoustic, live show"));
        categories.add(createCategory("Thể thao", "Các sự kiện thể thao, giải đấu, hoạt động vận động"));
        categories.add(createCategory("Công nghệ", "Workshop, hội thảo, triển lãm về công nghệ"));
        categories.add(createCategory("Giáo dục", "Seminar, khóa học, định hướng, chia sẻ kiến thức"));
        categories.add(createCategory("Ẩm thực", "Lễ hội ẩm thực, trải nghiệm món ăn, cooking class"));
        categories.add(createCategory("Du lịch", "Sự kiện khám phá, trải nghiệm, kết nối du lịch"));
        categories.add(createCategory("Nghệ thuật", "Triển lãm, vẽ tranh, biểu diễn nghệ thuật"));
        categories.add(createCategory("Kinh doanh", "Networking, startup, đầu tư, hội thảo doanh nghiệp"));
        categories.add(createCategory("Giải trí", "Talkshow, gameshow, fan meeting, hoạt động cộng đồng"));
        categories.add(createCategory("Thời trang", "Show diễn, workshop, triển lãm thời trang"));

        categoryRepository.saveAll(categories);
        System.out.println("Seeded " + categories.size() + " categories");
    }

    private Category createCategory(String name, String description) {
        Category category = new Category();
        category.setName(name);
        category.setDescription(description);
        return category;
    }
}
