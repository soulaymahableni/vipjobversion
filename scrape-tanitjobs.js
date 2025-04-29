const axios = require("axios");
const cheerio = require("cheerio");

const scrapeTanitJobs = async () => {
  try {
    // Make request to TanitJobs
    const response = await axios.get("https://www.tanitjobs.com/");
    const data = response?.data;

    // Initialize cheerio API with response body (HTML)
    const $ = cheerio.load(data);

    // Array to store all job listings
    const jobs = [];

    // Find all job listings
    $(".job-card").each((_, element) => {
      const job = {
        id: $(element).attr("id"),
        title: $(element).find(".job-title").text().trim(),
        company: $(element).find(".company-name").text().trim(),
        location: $(element).find(".job-location").text().trim(),
        type: $(element).find(".job-type").text().trim(),
        description: $(element).find(".job-description").text().trim(),
        category: $(element).find(".job-category").text().trim(),
        date: $(element).find(".job-date").text().trim(),
        salary: $(element).find(".job-salary").text().trim(),
        requirements: $(element).find(".job-requirements").text().trim(),
        benefits: $(element).find(".job-benefits").text().trim(),
        url: $(element).find("a").attr("href")
      };

      jobs.push(job);
    });

    return jobs;
  } catch (error) {
    console.error("Error scraping TanitJobs:", error);
    throw error;
  }
};

module.exports = scrapeTanitJobs;
