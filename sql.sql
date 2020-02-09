
create database pbscan;
use pbscan;

DROP TABLE IF EXISTS `issues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `issues` (
  `id` int(50) NOT NULL AUTO_INCREMENT,
  `rid` varchar(40) NOT NULL,
  `token` varchar(40) DEFAULT NULL,
  `issueName` varchar(100) DEFAULT NULL,
  `issueRequest` text DEFAULT NULL,
  `issueSeverity` varchar(20) DEFAULT NULL,
  `issueConfidence` varchar(20) DEFAULT NULL,
  `issueDetail` text DEFAULT NULL,
  `issueUrl` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=149 DEFAULT CHARSET=utf8;


--
-- Table structure for table `requests`
--

DROP TABLE IF EXISTS `requests`;
CREATE TABLE `requests` (
  `id` int(32) NOT NULL AUTO_INCREMENT,
  `rid` varchar(40) DEFAULT NULL,
  `token` varchar(40) DEFAULT NULL,
  `method` varchar(40) DEFAULT NULL,
  `host` varchar(255) DEFAULT NULL,
  `port` varchar(40) DEFAULT NULL,
  `path` text DEFAULT NULL,
  `body` text DEFAULT NULL,
  `scan_burp` int(4) DEFAULT 0,
  `scan_poc` int(4) DEFAULT 0,
  `update_time` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;



DROP TABLE IF EXISTS `results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `results` (
  `id` int(50) NOT NULL AUTO_INCREMENT,
  `rid` varchar(40) NOT NULL,
  `token` varchar(40) DEFAULT NULL,
  `status` varchar(20) DEFAULT 'not scan',
  `hide` tinyint DEFAULT 0,
  `request_num` smallint(6) DEFAULT '0',
  `issues_num` tinyint(4) DEFAULT '0',
  `insert_point` tinyint(4) DEFAULT '0',
  `result_poc` varchar(40) DEFAULT 'not scan yet',
  `saveFile` varchar(100) DEFAULT NULL,
  `scanTime` varchar(30) DEFAULT NULL,
  `scanUrl` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=105 DEFAULT CHARSET=utf8;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `admin`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `admin` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `token` varchar(40) NOT NULL,
  `username` varchar(20) NOT NULL,
  `password` char(32) NOT NULL,
  `email` varchar(50) DEFAULT NULL,
  `delete_time` varchar(30) DEFAULT NULL,
  `status` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=11 DEFAULT CHARSET=utf8;

LOCK TABLES `admin` WRITE;
/*!40000 ALTER TABLE `admin` DISABLE KEYS */;
INSERT INTO `admin` VALUES (1,'26a696bdcb160b8c274b37af6b9bb625','admin',md5('admin'),'2461805286@qq.com',NULL,1);
INSERT INTO `admin` VALUES (2,'parse_burp_log','pbscan',md5('pbscan'),'rivirsec@qq.com',NULL,1);
/*!40000 ALTER TABLE `admin` ENABLE KEYS */;
UNLOCK TABLES;
